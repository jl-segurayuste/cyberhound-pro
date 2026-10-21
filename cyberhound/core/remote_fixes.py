"""
Registro de los fixes remotos aplicados, para poder deshacerlos.

Cada fix guarda la acción inversa que se calculó a partir del estado previo del host
(RemoteAuditor.undo_action). Vive en la BD de la organización: cada una ve y deshace solo
los suyos.
"""
from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime

REMOTE_FIXES_TABLE = """
CREATE TABLE IF NOT EXISTS remote_fixes (
    id          TEXT PRIMARY KEY,
    ts          TEXT NOT NULL,
    username    TEXT DEFAULT '',
    host        TEXT NOT NULL,
    finding_id  TEXT NOT NULL,
    action      TEXT NOT NULL,
    undo        TEXT,
    message     TEXT DEFAULT '',
    undone_at   TEXT,
    undone_by   TEXT
);
"""


def _decode(row: dict) -> dict:
    d = dict(row)
    d["action"] = json.loads(d["action"])
    d["undo"] = json.loads(d["undo"]) if d.get("undo") else None
    d["reversible"] = d["undo"] is not None and not d.get("undone_at")
    return d


class RemoteFixesMixin:
    async def _run(self, sql: str, *args) -> int: ...
    async def _rows(self, sql: str, *args) -> list[dict]: ...

    async def add_remote_fix(self, host: str, finding_id: str, action: dict, undo: dict | None,
                             username: str = "", message: str = "") -> str:
        fid = secrets.token_hex(6)
        await self._run("INSERT INTO remote_fixes (id,ts,username,host,finding_id,action,undo,message) "
                        "VALUES (?,?,?,?,?,?,?,?)", fid, datetime.now(UTC).isoformat(), username, host,
                        finding_id, json.dumps(action), json.dumps(undo) if undo else None, message[:300])
        return fid

    async def list_remote_fixes(self, limit: int = 100) -> list[dict]:
        rows = await self._rows("SELECT * FROM remote_fixes ORDER BY ts DESC LIMIT ?", max(1, min(int(limit), 500)))
        return [_decode(r) for r in rows]

    async def get_remote_fix(self, fix_id: str) -> dict | None:
        rows = await self._rows("SELECT * FROM remote_fixes WHERE id=?", fix_id)
        return _decode(rows[0]) if rows else None

    async def mark_remote_fix_undone(self, fix_id: str, username: str) -> bool:
        """Marca el fix como deshecho; False si ya lo estaba (dos clics a la vez no lo deshacen dos veces)."""
        return await self._run("UPDATE remote_fixes SET undone_at=?, undone_by=? WHERE id=? AND undone_at IS NULL",
                               datetime.now(UTC).isoformat(), username, fix_id) > 0

    async def clear_remote_fix_undone(self, fix_id: str) -> None:
        await self._run("UPDATE remote_fixes SET undone_at=NULL, undone_by=NULL WHERE id=?", fix_id)
