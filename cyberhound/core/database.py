"""
Capa de persistencia SQLite para CyberHound Pro.

Tablas:
  scans        — histórico de ejecuciones (tipo, timestamp, duración, score)
  findings     — hallazgos de cada scan
  assets       — inventario persistente de dispositivos de red
  suppressions — falsos positivos suprimidos por el usuario
  users        — gestión de usuarios con roles
  notifications— cola de notificaciones pendientes de enviar
"""
from __future__ import annotations

import fnmatch
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiosqlite

from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("database")

DB_VERSION = 3
DEFAULT_DB_PATH = Path.home() / ".cyberhound" / "cyberhound.db"

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
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
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    finding_id  TEXT NOT NULL,
    category    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    remediation TEXT,
    evidence    TEXT,
    auto_fix    INTEGER DEFAULT 0,
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
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id_pattern  TEXT NOT NULL UNIQUE,
    reason              TEXT NOT NULL,
    created_by          TEXT NOT NULL,
    created_at          TEXT NOT NULL,
    expires_at          TEXT
);
CREATE TABLE IF NOT EXISTS users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'viewer',
    created_at    TEXT NOT NULL,
    last_login    TEXT,
    active        INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
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


@dataclass
class AssetRecord:
    ip:           str
    mac:          str = ""
    hostname:     str = ""
    vendor:       str = ""
    os_name:      str = ""
    open_ports:   str = "[]"
    risk_level:   str = "unknown"
    first_seen:   str = field(default_factory=lambda: _now())
    last_seen:    str = field(default_factory=lambda: _now())
    is_authorized: int = 1
    notes:        str = ""


@dataclass
class UserRecord:
    username:      str
    password_hash: str
    role:          str = "viewer"
    created_at:    str = field(default_factory=lambda: _now())
    last_login:    Optional[str] = None
    active:        int = 1


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: Path = DEFAULT_DB_PATH) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    async def init(self) -> None:
        async with aiosqlite.connect(str(self.path)) as db:
            await db.executescript(SCHEMA)
            async with db.execute("SELECT MAX(version) FROM schema_version") as cur:
                row = await cur.fetchone()
                current = row[0] if row and row[0] else 0
            if current < DB_VERSION:
                await db.execute(
                    "INSERT OR IGNORE INTO schema_version VALUES (?,?)",
                    (DB_VERSION, _now()),
                )
            await db.commit()
        self.path.chmod(0o600)
        logger.info("Base de datos inicializada: %s", self.path)

    # ── Scans ─────────────────────────────────────────────────────────────────

    async def create_scan(
        self, scan_type: str, target: str = "localhost",
        triggered_by: str = "manual",
    ) -> int:
        async with aiosqlite.connect(str(self.path)) as db:
            async with db.execute(
                "INSERT INTO scans (scan_type,target,started_at,status,triggered_by)"
                " VALUES (?,?,?,'running',?)",
                (scan_type, target, _now(), triggered_by),
            ) as cur:
                scan_id = cur.lastrowid
            await db.commit()
        return scan_id

    async def complete_scan(
        self, scan_id: int, findings: list[Finding], score: Optional[int] = None
    ) -> None:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            if f.severity in counts:
                counts[f.severity] += 1
        if score is None:
            score = max(0, 100
                        - counts["critical"] * 20
                        - counts["high"] * 10
                        - counts["medium"] * 4
                        - counts["low"])
        now = _now()
        async with aiosqlite.connect(str(self.path)) as db:
            async with db.execute(
                "SELECT started_at FROM scans WHERE id=?", (scan_id,)
            ) as cur:
                row = await cur.fetchone()
            try:
                duration = time.time() - datetime.fromisoformat(row[0]).timestamp()
            except Exception:
                duration = 0.0
            await db.execute(
                """UPDATE scans SET finished_at=?,duration_s=?,score=?,
                   total_findings=?,critical=?,high=?,medium=?,low=?,
                   status='completed' WHERE id=?""",
                (now, duration, score, len(findings),
                 counts["critical"], counts["high"], counts["medium"], counts["low"],
                 scan_id),
            )
            await db.executemany(
                """INSERT INTO findings
                   (scan_id,finding_id,category,severity,title,description,
                    remediation,evidence,auto_fix,file_path,line_number,source_host)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                [(scan_id, f.id, f.category, f.severity, f.title,
                  f.description, f.remediation, f.evidence,
                  int(f.auto_fix), f.file_path, f.line_number, f.source_host)
                 for f in findings],
            )
            await db.commit()
        logger.info("Scan %d completado: %d hallazgos, score=%d", scan_id, len(findings), score)

    async def fail_scan(self, scan_id: int) -> None:
        async with aiosqlite.connect(str(self.path)) as db:
            await db.execute(
                "UPDATE scans SET status='failed',finished_at=? WHERE id=?",
                (_now(), scan_id),
            )
            await db.commit()

    async def get_scan_history(
        self, scan_type: Optional[str] = None, limit: int = 50
    ) -> list[dict]:
        q = "SELECT * FROM scans"
        p: list = []
        if scan_type:
            q += " WHERE scan_type=?"
            p.append(scan_type)
        q += " ORDER BY started_at DESC LIMIT ?"
        p.append(limit)
        async with aiosqlite.connect(str(self.path)) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(q, p) as cur:
                return [dict(r) for r in await cur.fetchall()]

    async def get_scan_findings(self, scan_id: int) -> list[dict]:
        async with aiosqlite.connect(str(self.path)) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """SELECT * FROM findings WHERE scan_id=?
                   ORDER BY CASE severity
                     WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                     WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END""",
                (scan_id,),
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]

    async def get_score_trend(self, scan_type: str = "audit", days: int = 30) -> list[dict]:
        async with aiosqlite.connect(str(self.path)) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """SELECT started_at,score,total_findings,critical,high
                   FROM scans WHERE scan_type=? AND status='completed'
                     AND started_at >= datetime('now',? || ' days')
                   ORDER BY started_at ASC""",
                (scan_type, f"-{days}"),
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]

    async def get_comparison(self, scan_id: int) -> dict:
        async with aiosqlite.connect(str(self.path)) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT scan_type FROM scans WHERE id=?", (scan_id,)
            ) as cur:
                row = await cur.fetchone()
                if not row:
                    return {}
                scan_type = row["scan_type"]
            async with db.execute(
                """SELECT id FROM scans WHERE scan_type=? AND status='completed'
                   AND id<? ORDER BY id DESC LIMIT 1""",
                (scan_type, scan_id),
            ) as cur:
                prev_row = await cur.fetchone()
                if not prev_row:
                    return {"first_scan": True}
                prev_id = prev_row["id"]
            async with db.execute(
                "SELECT finding_id,severity FROM findings WHERE scan_id=?", (scan_id,)
            ) as cur:
                current = {r["finding_id"]: r["severity"] for r in await cur.fetchall()}
            async with db.execute(
                "SELECT finding_id,severity FROM findings WHERE scan_id=?", (prev_id,)
            ) as cur:
                previous = {r["finding_id"]: r["severity"] for r in await cur.fetchall()}
        new_ids  = set(current) - set(previous)
        resolved = set(previous) - set(current)
        return {
            "previous_scan_id": prev_id,
            "new":      [{"id": i, "severity": current[i]}  for i in new_ids],
            "resolved": [{"id": i, "severity": previous[i]} for i in resolved],
            "unchanged": len(set(current) & set(previous)),
        }

    async def mark_finding_fixed(self, scan_id: int, finding_id: str, fixed_by: str) -> None:
        async with aiosqlite.connect(str(self.path)) as db:
            await db.execute(
                "UPDATE findings SET fixed_at=?,fixed_by=? WHERE scan_id=? AND finding_id=?",
                (_now(), fixed_by, scan_id, finding_id),
            )
            await db.commit()

    # ── Assets ────────────────────────────────────────────────────────────────

    async def upsert_asset(self, asset: AssetRecord) -> bool:
        now = _now()
        async with aiosqlite.connect(str(self.path)) as db:
            async with db.execute(
                "SELECT ip FROM assets WHERE ip=?", (asset.ip,)
            ) as cur:
                is_new = (await cur.fetchone()) is None
            if is_new:
                await db.execute(
                    """INSERT INTO assets
                       (ip,mac,hostname,vendor,os_name,open_ports,
                        risk_level,first_seen,last_seen,is_authorized)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (asset.ip, asset.mac, asset.hostname, asset.vendor,
                     asset.os_name, asset.open_ports, asset.risk_level,
                     now, now, asset.is_authorized),
                )
            else:
                await db.execute(
                    """UPDATE assets SET mac=?,hostname=?,vendor=?,os_name=?,
                       open_ports=?,risk_level=?,last_seen=? WHERE ip=?""",
                    (asset.mac, asset.hostname, asset.vendor, asset.os_name,
                     asset.open_ports, asset.risk_level, now, asset.ip),
                )
            await db.commit()
        return is_new

    async def get_assets(self) -> list[dict]:
        async with aiosqlite.connect(str(self.path)) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM assets ORDER BY last_seen DESC"
            ) as cur:
                rows = await cur.fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    try:
                        d["open_ports"] = json.loads(d.get("open_ports", "[]"))
                    except Exception:
                        d["open_ports"] = []
                    result.append(d)
                return result

    async def get_new_assets_since(self, hours: int = 24) -> list[dict]:
        async with aiosqlite.connect(str(self.path)) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM assets WHERE first_seen >= datetime('now',? || ' hours')",
                (f"-{hours}",),
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]

    async def set_asset_authorized(self, ip: str, authorized: bool, notes: str = "") -> None:
        async with aiosqlite.connect(str(self.path)) as db:
            await db.execute(
                "UPDATE assets SET is_authorized=?,notes=? WHERE ip=?",
                (int(authorized), notes, ip),
            )
            await db.commit()

    # ── Suppressions ──────────────────────────────────────────────────────────

    async def add_suppression(
        self, pattern: str, reason: str, created_by: str,
        expires_at: Optional[str] = None,
    ) -> None:
        async with aiosqlite.connect(str(self.path)) as db:
            await db.execute(
                """INSERT OR REPLACE INTO suppressions
                   (finding_id_pattern,reason,created_by,created_at,expires_at)
                   VALUES (?,?,?,?,?)""",
                (pattern, reason, created_by, _now(), expires_at),
            )
            await db.commit()

    async def remove_suppression(self, pattern: str) -> None:
        async with aiosqlite.connect(str(self.path)) as db:
            await db.execute(
                "DELETE FROM suppressions WHERE finding_id_pattern=?", (pattern,)
            )
            await db.commit()

    async def get_suppressions(self) -> list[dict]:
        async with aiosqlite.connect(str(self.path)) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM suppressions ORDER BY created_at DESC"
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]

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
        suppressed = len(findings) - len(result)
        if suppressed:
            logger.info("Suprimidos %d findings (falsos positivos)", suppressed)
        return result

    # ── Users ─────────────────────────────────────────────────────────────────

    async def ensure_admin_exists(self, username: str, password_hash: str) -> None:
        if not await self.get_user(username):
            await self.create_user(UserRecord(
                username=username, password_hash=password_hash, role="admin"
            ))
            logger.info("Usuario admin '%s' creado", username)

    async def create_user(self, user: UserRecord) -> None:
        async with aiosqlite.connect(str(self.path)) as db:
            await db.execute(
                "INSERT INTO users (username,password_hash,role,created_at,active)"
                " VALUES (?,?,?,?,?)",
                (user.username, user.password_hash, user.role, user.created_at, user.active),
            )
            await db.commit()

    async def get_user(self, username: str) -> Optional[dict]:
        async with aiosqlite.connect(str(self.path)) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM users WHERE username=? AND active=1", (username,)
            ) as cur:
                row = await cur.fetchone()
                return dict(row) if row else None

    async def update_last_login(self, username: str) -> None:
        async with aiosqlite.connect(str(self.path)) as db:
            await db.execute(
                "UPDATE users SET last_login=? WHERE username=?", (_now(), username)
            )
            await db.commit()

    async def update_user(self, username: str, **kwargs) -> None:
        allowed = {"password_hash", "role", "active"}
        fields = {k: v for k, v in kwargs.items() if k in allowed}
        if not fields:
            return
        sets = ", ".join(f"{k}=?" for k in fields)
        async with aiosqlite.connect(str(self.path)) as db:
            await db.execute(
                f"UPDATE users SET {sets} WHERE username=?",
                [*fields.values(), username],
            )
            await db.commit()

    async def list_users(self) -> list[dict]:
        async with aiosqlite.connect(str(self.path)) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT username,role,created_at,last_login,active FROM users"
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]

    # ── Notifications ─────────────────────────────────────────────────────────

    async def add_notification(
        self, message: str, level: str = "info", scan_id: Optional[int] = None
    ) -> None:
        async with aiosqlite.connect(str(self.path)) as db:
            await db.execute(
                "INSERT INTO notifications (scan_id,level,message,created_at) VALUES (?,?,?,?)",
                (scan_id, level, message, _now()),
            )
            await db.commit()

    async def get_pending_notifications(self) -> list[dict]:
        async with aiosqlite.connect(str(self.path)) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM notifications WHERE sent=0 ORDER BY created_at ASC"
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]

    async def mark_notification_sent(self, notif_id: int) -> None:
        async with aiosqlite.connect(str(self.path)) as db:
            await db.execute(
                "UPDATE notifications SET sent=1,sent_at=? WHERE id=?", (_now(), notif_id)
            )
            await db.commit()

    # ── Dashboard stats ───────────────────────────────────────────────────────

    async def get_dashboard_stats(self) -> dict:
        async with aiosqlite.connect(str(self.path)) as db:
            db.row_factory = aiosqlite.Row
            last_scans = {}
            for stype in ("audit", "malware", "network", "code"):
                async with db.execute(
                    "SELECT * FROM scans WHERE scan_type=? AND status='completed'"
                    " ORDER BY started_at DESC LIMIT 1",
                    (stype,),
                ) as cur:
                    row = await cur.fetchone()
                    last_scans[stype] = dict(row) if row else None

            async with db.execute("SELECT COUNT(*) as n FROM assets") as cur:
                row = await cur.fetchone()
                total_assets = row["n"] if row else 0

            async with db.execute(
                "SELECT COUNT(*) as n FROM assets WHERE is_authorized=0"
            ) as cur:
                row = await cur.fetchone()
                unauthorized = row["n"] if row else 0

            async with db.execute(
                """SELECT date(started_at) as day, AVG(score) as avg_score
                   FROM scans WHERE scan_type='audit' AND status='completed'
                     AND started_at >= datetime('now','-30 days')
                   GROUP BY day ORDER BY day ASC"""
            ) as cur:
                score_trend = [dict(r) for r in await cur.fetchall()]

            critical_findings: list[dict] = []
            if last_scans.get("audit"):
                async with db.execute(
                    "SELECT * FROM findings WHERE scan_id=? AND severity='critical'"
                    " AND fixed_at IS NULL LIMIT 10",
                    (last_scans["audit"]["id"],),
                ) as cur:
                    critical_findings = [dict(r) for r in await cur.fetchall()]

        return {
            "last_scans":          last_scans,
            "total_assets":        total_assets,
            "unauthorized_assets": unauthorized,
            "score_trend":         score_trend,
            "critical_findings":   critical_findings,
        }
